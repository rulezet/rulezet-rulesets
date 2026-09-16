rule TTP_XOR_QUAD_CurrentVersionRun_e40d {
  strings:
    $key_e40d = { b7 62 [2] 93 6c [2] b8 40 [2] 96 62 [2] 82 79 [2] 8d 63 [2] 93 7e [2] 91 7f [2] 8a 79 [2] 96 7e [2] 8a 51 }

  condition:
    any of them
}