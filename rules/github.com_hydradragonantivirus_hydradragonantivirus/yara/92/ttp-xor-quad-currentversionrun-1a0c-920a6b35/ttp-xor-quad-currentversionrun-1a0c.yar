rule TTP_XOR_QUAD_CurrentVersionRun_1a0c {
  strings:
    $key_1a0c = { 49 63 [2] 6d 6d [2] 46 41 [2] 68 63 [2] 7c 78 [2] 73 62 [2] 6d 7f [2] 6f 7e [2] 74 78 [2] 68 7f [2] 74 50 }

  condition:
    any of them
}