rule TTP_XOR_QUAD_CurrentVersionRun_133c {
  strings:
    $key_133c = { 40 53 [2] 64 5d [2] 4f 71 [2] 61 53 [2] 75 48 [2] 7a 52 [2] 64 4f [2] 66 4e [2] 7d 48 [2] 61 4f [2] 7d 60 }

  condition:
    any of them
}