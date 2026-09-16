rule TTP_XOR_QUAD_CurrentVersionRun_212d {
  strings:
    $key_212d = { 72 42 [2] 56 4c [2] 7d 60 [2] 53 42 [2] 47 59 [2] 48 43 [2] 56 5e [2] 54 5f [2] 4f 59 [2] 53 5e [2] 4f 71 }

  condition:
    any of them
}