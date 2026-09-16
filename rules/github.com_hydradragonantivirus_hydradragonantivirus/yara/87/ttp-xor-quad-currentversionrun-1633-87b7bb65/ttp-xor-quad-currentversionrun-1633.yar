rule TTP_XOR_QUAD_CurrentVersionRun_1633 {
  strings:
    $key_1633 = { 45 5c [2] 61 52 [2] 4a 7e [2] 64 5c [2] 70 47 [2] 7f 5d [2] 61 40 [2] 63 41 [2] 78 47 [2] 64 40 [2] 78 6f }

  condition:
    any of them
}