rule sig_20160517_e05d896de327c79ba34ae076b8fefced {
  meta:
    description = "datamaliciousorder - file 20160517_e05d896de327c79ba34ae076b8fefced.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d628378078ef8aeeb0c4a210fb2942208681715801ef4409f84e0ff2e071ece4"

  strings:
    $s1 = "var pq2is='vhs4awacxa3oreyjwh atp4yyjvrp11pqkpcnwgzrk3a1iz3fk31ky4rqs2tyq2pirhqthaiygrsojhnjjpj=nqmla\\'pxudytsy1dgcow441nessfgi" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}