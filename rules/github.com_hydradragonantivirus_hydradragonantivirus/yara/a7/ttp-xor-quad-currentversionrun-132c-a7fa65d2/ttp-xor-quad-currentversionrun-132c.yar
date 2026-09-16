rule TTP_XOR_QUAD_CurrentVersionRun_132c {
  strings:
    $key_132c = { 40 43 [2] 64 4d [2] 4f 61 [2] 61 43 [2] 75 58 [2] 7a 42 [2] 64 5f [2] 66 5e [2] 7d 58 [2] 61 5f [2] 7d 70 }

  condition:
    any of them
}