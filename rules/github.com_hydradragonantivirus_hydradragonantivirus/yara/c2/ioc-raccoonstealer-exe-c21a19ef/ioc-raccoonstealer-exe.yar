import "hash"
rule IOC_RACCOONSTEALER_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_RACCOONSTEALER_LAB"
    date_IOC   = "2023-11-14 04:33:07"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "RACCOONSTEALER"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "bdcb0564911bdb1f151d4f58f82bce75a8c861ee251ea7273487a34fec865654" or
    hash.sha256(0, filesize) == "d74b9b445cc4cb4fef7ce48910ef2f930bb044dc09221df368ff3353aff70841" or
    hash.sha256(0, filesize) == "f6be22baa5e6bc398c0130a7d93411166fd2441722cdd6a3ec3f7205a384acfe" or
    hash.sha256(0, filesize) == "79ead2d23149eaa2413377b314d1e4351cbe2451839cd652ed51c5c2e9a006dc" or
    hash.sha256(0, filesize) == "8e6021918d108cbb2e19ab300a03e25b1e1e0c6e621754f5940e6db2ac195d0a" or
    hash.sha256(0, filesize) == "f14734d04f355fa903c6482fc4f3662c3ac1ab892ad14f2f135ae357d1f04db4" or
    hash.sha256(0, filesize) == "c6d0d98dd43822fe12a1d785df4e391db3c92846b0473b54762fbb929de6f5cb" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}