rule TTP_XOR_QUAD_CurrentVersionRun_e40c {
  strings:
    $key_e40c = { b7 63 [2] 93 6d [2] b8 41 [2] 96 63 [2] 82 78 [2] 8d 62 [2] 93 7f [2] 91 7e [2] 8a 78 [2] 96 7f [2] 8a 50 }

  condition:
    any of them
}