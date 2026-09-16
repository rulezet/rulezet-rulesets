rule sig_20170404_6a2cce2ba0dcee0647a17c28bdfb6999 {
  meta:
    description = "datamaliciousorder - file 20170404_6a2cce2ba0dcee0647a17c28bdfb6999.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81becd0c519cf40b0647f09dd426b6d3bc7c3653ce8d70beb2e4db5b4324bfc9"

  strings:
    $s1 = "while(tersa < 100){tersa++;}" fullword ascii
    $s2 = "var rima = 500;" fullword ascii
    $s3 = "var jamie = new Array(kus,'t',\"\",\":\",'p','h','S','a',\"T\",'');" fullword ascii
    $s4 = "var hist = 'ht'+\"\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}