rule TTP_XOR_QUAD_CurrentVersionRun_e699 {
  strings:
    $key_e699 = { b5 f6 [2] 91 f8 [2] ba d4 [2] 94 f6 [2] 80 ed [2] 8f f7 [2] 91 ea [2] 93 eb [2] 88 ed [2] 94 ea [2] 88 c5 }

  condition:
    any of them
}