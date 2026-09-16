rule TTP_XOR_QUAD_CurrentVersionRun_e60d {
  strings:
    $key_e60d = { b5 62 [2] 91 6c [2] ba 40 [2] 94 62 [2] 80 79 [2] 8f 63 [2] 91 7e [2] 93 7f [2] 88 79 [2] 94 7e [2] 88 51 }

  condition:
    any of them
}