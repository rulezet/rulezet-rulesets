rule sig_20170402_620f42a48c2375d42e73510482873a8b {
  meta:
    description = "datamaliciousorder - file 20170402_620f42a48c2375d42e73510482873a8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0012764fcd591505ce891927c413fbe10a04106bef791e95891c83e719095db8"

  strings:
    $s1 = "var ahat = new Array(kus,'t',\"GET\",\":\",'p','h','S','a',\"T\",'');" fullword ascii
    $s2 = "while(tersa < 10){tersa++;}" fullword ascii
    $s3 = "var hist = 'ht';" fullword ascii

  condition:
    uint16(0) == 0x6574 and
    all of them
}