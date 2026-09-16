rule TTP_XOR_QUAD_CurrentVersionRun_0a10 {
  strings:
    $key_0a10 = { 59 7f [2] 7d 71 [2] 56 5d [2] 78 7f [2] 6c 64 [2] 63 7e [2] 7d 63 [2] 7f 62 [2] 64 64 [2] 78 63 [2] 64 4c }

  condition:
    any of them
}