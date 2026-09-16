rule sig_20161127_7726d37763064cd09d42044c96721bad {
  meta:
    description = "datamaliciousorder - file 20161127_7726d37763064cd09d42044c96721bad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7cf69eda7d759749590cd161c628f98ca016af45cc9702aedd83f3261ecaf99"

  strings:
    $s1 = "var cilxabj = new Function([\"ret\", '#', '#'].botnyzi() + [\"urn\", '#', '#'].botnyzi() + [\" Ac\", '#'].botnyzi() + [\"tiv\", " ascii
    $s2 = "var cilxabj = new Function([\"ret\", '#', '#'].botnyzi() + [\"urn\", '#', '#'].botnyzi() + [\" Ac\", '#'].botnyzi() + [\"tiv\", " ascii
    $s3 = "Array[\"prototype\"][\"botnyzi\"] = new Function(\"var waxnymto = this; return  waxnymto[1-1];\");" fullword ascii
    $s4 = "switch (omsecz[[qdyvpiv][0]] > 4) {" fullword ascii

  condition:
    uint16(0) == 0x7241 and
    all of them
}