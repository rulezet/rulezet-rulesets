rule TTP_XOR_QUAD_CurrentVersionRun_6a10 {
  strings:
    $key_6a10 = { 39 7f [2] 1d 71 [2] 36 5d [2] 18 7f [2] 0c 64 [2] 03 7e [2] 1d 63 [2] 1f 62 [2] 04 64 [2] 18 63 [2] 04 4c }

  condition:
    any of them
}