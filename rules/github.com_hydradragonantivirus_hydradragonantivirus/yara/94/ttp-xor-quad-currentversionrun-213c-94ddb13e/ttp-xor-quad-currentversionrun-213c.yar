rule TTP_XOR_QUAD_CurrentVersionRun_213c {
  strings:
    $key_213c = { 72 53 [2] 56 5d [2] 7d 71 [2] 53 53 [2] 47 48 [2] 48 52 [2] 56 4f [2] 54 4e [2] 4f 48 [2] 53 4f [2] 4f 60 }

  condition:
    any of them
}