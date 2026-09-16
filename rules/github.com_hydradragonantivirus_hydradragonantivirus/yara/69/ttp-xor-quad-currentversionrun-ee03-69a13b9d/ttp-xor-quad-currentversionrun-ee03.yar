rule TTP_XOR_QUAD_CurrentVersionRun_ee03 {
  strings:
    $key_ee03 = { bd 6c [2] 99 62 [2] b2 4e [2] 9c 6c [2] 88 77 [2] 87 6d [2] 99 70 [2] 9b 71 [2] 80 77 [2] 9c 70 [2] 80 5f }

  condition:
    any of them
}