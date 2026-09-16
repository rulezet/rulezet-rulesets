rule TTP_XOR_QUAD_CurrentVersionRun_1a10 {
  strings:
    $key_1a10 = { 49 7f [2] 6d 71 [2] 46 5d [2] 68 7f [2] 7c 64 [2] 73 7e [2] 6d 63 [2] 6f 62 [2] 74 64 [2] 68 63 [2] 74 4c }

  condition:
    any of them
}