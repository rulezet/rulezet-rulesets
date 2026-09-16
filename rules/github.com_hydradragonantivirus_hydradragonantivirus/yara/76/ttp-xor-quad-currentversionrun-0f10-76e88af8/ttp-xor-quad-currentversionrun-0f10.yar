rule TTP_XOR_QUAD_CurrentVersionRun_0f10 {
  strings:
    $key_0f10 = { 5c 7f [2] 78 71 [2] 53 5d [2] 7d 7f [2] 69 64 [2] 66 7e [2] 78 63 [2] 7a 62 [2] 61 64 [2] 7d 63 [2] 61 4c }

  condition:
    any of them
}