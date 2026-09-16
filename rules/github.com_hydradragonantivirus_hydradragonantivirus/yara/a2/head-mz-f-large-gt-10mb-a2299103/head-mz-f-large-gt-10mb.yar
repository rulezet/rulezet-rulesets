rule head_mz_f_large_gt_10mb {
  condition:
    uint16be(0) == 0x4d5a
    and filesize > 10000KB
}