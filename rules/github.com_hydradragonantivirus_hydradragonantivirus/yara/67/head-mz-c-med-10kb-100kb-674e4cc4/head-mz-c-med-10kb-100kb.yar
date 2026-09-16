rule head_mz_c_med_10kb_100kb {
  condition:
    uint16be(0) == 0x4d5a
    and filesize > 10KB and filesize < 100KB
}