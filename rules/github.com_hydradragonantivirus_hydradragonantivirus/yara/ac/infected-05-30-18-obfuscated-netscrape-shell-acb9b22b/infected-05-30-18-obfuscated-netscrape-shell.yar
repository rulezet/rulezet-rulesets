rule _infected_05_30_18_obfuscated_netscrape_shell {
  meta:
    description = "case113 - file -.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-05-30"
    hash1       = "5c05b22d161a82c30f63426a6c161ddbbd47d7acf867e9c5958ccb682be5a720"

  strings:
    $s1  = "$c0000101101010001010101101111110110101010111111111110101010101sdc0s1dc0sd1c0s1dc0s1d0cs1d0cs1dcsdc1sdc1s0dc1sd0cs1dc0s1dcs1d1g0" ascii
    $s2  = "dyrUnWXdzU9Ml9J0jOvB2bxvXGQkadeufKUvqOFFl8fqEo2EqI2v3QYBVaiYoiCDsw7dHEcipftIeyUcmMs1R1k5Pnvhl757hM0fQdD/pjjyFTP2vuw8xLDtAVrGcpGn" ascii
    $s3  = "MahWyawtVOtzh7WH7J6x3QnQb87tiUV+BN+iXzx9VNn07OoG2hjgdqh6zphJ2mmaWj74OwMyyWZkNwhAM+u1s2sbPClE34JVH2cTh0/mocSBLLpeyeO5pFfQRLnwTQaa" ascii
    $s4  = "2DDsNfthY3Rx+U7W/NijJE6rXEWSER4jumqzPfMMbWavn+VCHod6jp8mx1iH+2/fn7csuf92I9tgetGwUiQRAKblyzS2Mnq+Bw97C4GN/hAd9nTql9HuNeQpfsgowZwr" ascii
    $s5  = "nalanBEDllYrCJFnN6uyubiHhnl9chV9IghzN3WKaPcQbGMB4n/h212Z4deGpm99F0y8e5E8gDpV+rxUOrbRaA8tqlaSZ9hiaP2pDfraOhbuUXlbJiC8SgAsYQQXxUIE" ascii
    $s6  = "8/DCcYoPDgPm0HHXwqAW6tMPP5hYaYl7wLjD2XlqFiRzlKNFEqNB4/Hj6KoRKuAdvGgpwkyrVDNT4l6CH5gjqNeKAVmI/6SW4rsFZn5zJ10+vNTWhcV3U1SjZh181JdQ" ascii
    $s7  = "KPrZEslUzhQ+rrX2E/k2zgqBBMPbavzCF05ZvGbnCVGe4q/p/OFgwbInGVBdo5PdmAxRhORkeAKAEjtXD5S0Jz6jXJnwFZV89GEjX5/68T0/F953Dui4F92mzbB/jcbm" ascii
    $s8  = "HjmG/Va7vEKHywKL+Bn46tywk/neL6spXKhWTDoUffFtQwGuRuN3hcGHDQas5/Gk1SbGRvKQo8eTipiGjrv1mygeFo3RDf0FmjhcHeh66TVNh1CrQYklWFs2wT4S4pTr" ascii
    $s9  = "cAQ5mEZIM+bn3jChEqvb0TlCWTvnvAdCW+QpMu26HdhZFux5cyFLV7u7OLggW9tewsEQlObf8uGvSQimTAYglHV98NaWoDLl/1OTQdMjXHT+qaNuNNTc2FSnkJxJePI6" ascii
    $s10 = "/* Smart Tools Shop v5*/" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 80KB and
      (all of them)
    ) or (all of them)
}