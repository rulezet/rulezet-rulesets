rule head_mz_e_med_1mb_10mb {
  condition:
    uint16be(0) == 0x4d5a
    and filesize > 1000KB and filesize < 10000KB
}