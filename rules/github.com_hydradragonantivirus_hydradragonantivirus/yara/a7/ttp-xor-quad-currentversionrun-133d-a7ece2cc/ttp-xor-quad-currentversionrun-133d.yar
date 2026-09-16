rule TTP_XOR_QUAD_CurrentVersionRun_133d {
  strings:
    $key_133d = { 40 52 [2] 64 5c [2] 4f 70 [2] 61 52 [2] 75 49 [2] 7a 53 [2] 64 4e [2] 66 4f [2] 7d 49 [2] 61 4e [2] 7d 61 }

  condition:
    any of them
}