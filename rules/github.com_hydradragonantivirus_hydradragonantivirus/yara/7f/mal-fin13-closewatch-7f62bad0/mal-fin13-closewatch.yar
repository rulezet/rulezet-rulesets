rule MAL_FIN13_CLOSEWATCH {
  meta:
    description   = "Matches strings found in CLOSEWATCH JSP webshell and scanner used by FIN13 (AKA: ElephantBeetle, SQUAB SPIDER)"
    last_modified = "2024-04-05"
    author        = "@petermstewart"
    DaysofYara    = "96/100"
    sha256        = "e9e25584475ebf08957886725ebc99a2b85af7a992b6c6ae352c94e8d9c79101"
    ref           = "https://www.mandiant.com/resources/blog/fin13-cybercriminal-mexico"

  strings:
    $a1 = "host=\"localhost\";"
    $a2 = "pport=16998;"
    $b1 = "request.getParameter(\"psh3\")"
    $b2 = "request.getParameter(\"psh\")"
    $b3 = "request.getParameter(\"psh2\")"
    $b4 = "request.getParameter(\"c\")"
    $c1 = "ja!, perra xD"

  condition:
    filesize < 20KB and
    6 of them
}