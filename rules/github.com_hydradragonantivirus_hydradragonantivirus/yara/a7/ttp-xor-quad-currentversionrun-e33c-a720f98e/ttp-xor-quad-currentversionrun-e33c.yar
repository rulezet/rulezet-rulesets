rule TTP_XOR_QUAD_CurrentVersionRun_e33c {
  strings:
    $key_e33c = { b0 53 [2] 94 5d [2] bf 71 [2] 91 53 [2] 85 48 [2] 8a 52 [2] 94 4f [2] 96 4e [2] 8d 48 [2] 91 4f [2] 8d 60 }

  condition:
    any of them
}