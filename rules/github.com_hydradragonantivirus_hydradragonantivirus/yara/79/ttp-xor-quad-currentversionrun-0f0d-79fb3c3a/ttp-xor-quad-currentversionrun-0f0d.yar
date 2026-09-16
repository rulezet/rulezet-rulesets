rule TTP_XOR_QUAD_CurrentVersionRun_0f0d {
  strings:
    $key_0f0d = { 5c 62 [2] 78 6c [2] 53 40 [2] 7d 62 [2] 69 79 [2] 66 63 [2] 78 7e [2] 7a 7f [2] 61 79 [2] 7d 7e [2] 61 51 }

  condition:
    any of them
}