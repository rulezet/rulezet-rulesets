rule TTP_XOR_QUAD_CurrentVersionRun_e43c {
  strings:
    $key_e43c = { b7 53 [2] 93 5d [2] b8 71 [2] 96 53 [2] 82 48 [2] 8d 52 [2] 93 4f [2] 91 4e [2] 8a 48 [2] 96 4f [2] 8a 60 }

  condition:
    any of them
}