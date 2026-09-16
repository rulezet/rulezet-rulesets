rule infected_09_06_18_shells_py {
  meta:
    description = "shells - file py.alfa"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-09-06"
    hash1       = "3ef9d2cfd9c45c40d2e308ae8ac1b7f48b09f40409457a8836de39d2df832d32"

  strings:
    $x1  = "print '<html><head><title>Coded by ALFA TeAM - CGI Python</title><meta charset=\"UTF-8\"></head>'" fullword ascii
    $s2  = "print '<body onload=\"document.f.c.focus();\" bgcolor=\"#000000\" topmargin=\"0\" leftmargin=\"0\" marginwidth=\"0\" marginheigh" ascii
    $s3  = "Prompt = '['+getpass.getuser()+'@'+os.environ[\"SERVER_NAME\"]+' '+CurrentDir+']$'" fullword ascii
    $s4  = "print '<b>Command : ', cmd, '</b><br><br>'" fullword ascii
    $s5  = "import sys,cgi,os,getpass,base64,urllib" fullword ascii
    $s6  = ">Solevisible Cgi Python</b></font> Connected to '+os.environ[\"SERVER_NAME\"]+'</b></td></tr></table>'" fullword ascii
    $s7  = "cmd = form.getvalue('c')" fullword ascii
    $s8  = "cmd = 'cd ' + CurrentDir + ';' + cmd" fullword ascii
    $s9  = "ncmd = 'cd ' + dir + ';' + cmd + ';pwd'" fullword ascii
    $s10 = "\"0\" text=\"#FFFFFF\"><table border=\"1\" width=\"100%\" cellspacing=\"0\" cellpadding=\"2\"><tr><font color=\"red\"><b>Coded b" ascii
    $s11 = "rompt+' <input type=\"text\" name=\"c\" ><input type=\"submit\" size=\"30\" value=\">>\"></form>'" fullword ascii
    $s12 = "cmd = urllib.unquote(base64.b64decode(cmd))" fullword ascii
    $s13 = "if os.environ.has_key(\"SCRIPT_NAME\"):" fullword ascii
    $s14 = "errormess = '<center><h2>Something Went Wrong</h2><br><pre>'" fullword ascii
    $s15 = "nvisible ~ solevisible@gmail.com</b></font><td bgcolor=\"#000000\" bordercolor=\"#FFFFFF\" align=\"center\" width=\"1%\"><b><fon" ascii
    $s16 = "print '<xmp>'+alfaCmd(cmd)+'</xmp>'" fullword ascii
    $s17 = "print \"Content-type: text/html\\r\\n\"" fullword ascii
    $s18 = "a = f.getvalue().splitlines()" fullword ascii
    $s19 = "dir = form.getvalue('d')" fullword ascii
    $s20 = "CurrentDir = alfaCmd(ncmd).replace('\\n','')" fullword ascii

  condition:
    (uint16(0) == 0x2123 and
      filesize < 8KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}