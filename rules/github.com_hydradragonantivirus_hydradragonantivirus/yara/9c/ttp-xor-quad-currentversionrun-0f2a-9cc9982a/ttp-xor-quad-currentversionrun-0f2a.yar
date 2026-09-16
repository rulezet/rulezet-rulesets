rule TTP_XOR_QUAD_CurrentVersionRun_0f2a {
  strings:
    $key_0f2a = { 5c 45 [2] 78 4b [2] 53 67 [2] 7d 45 [2] 69 5e [2] 66 44 [2] 78 59 [2] 7a 58 [2] 61 5e [2] 7d 59 [2] 61 76 }

  condition:
    any of them
}