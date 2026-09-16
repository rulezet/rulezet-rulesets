rule TTP_XOR_QUAD_CurrentVersionRun_0f0c {
  strings:
    $key_0f0c = { 5c 63 [2] 78 6d [2] 53 41 [2] 7d 63 [2] 69 78 [2] 66 62 [2] 78 7f [2] 7a 7e [2] 61 78 [2] 7d 7f [2] 61 50 }

  condition:
    any of them
}