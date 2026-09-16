rule TTP_XOR_QUAD_CurrentVersionRun_e63d {
  strings:
    $key_e63d = { b5 52 [2] 91 5c [2] ba 70 [2] 94 52 [2] 80 49 [2] 8f 53 [2] 91 4e [2] 93 4f [2] 88 49 [2] 94 4e [2] 88 61 }

  condition:
    any of them
}