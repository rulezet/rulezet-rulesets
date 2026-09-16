rule TTP_XOR_QUAD_CurrentVersionRun_f1dc {
  strings:
    $key_f1dc = { a2 b3 [2] 86 bd [2] ad 91 [2] 83 b3 [2] 97 a8 [2] 98 b2 [2] 86 af [2] 84 ae [2] 9f a8 [2] 83 af [2] 9f 80 }

  condition:
    any of them
}