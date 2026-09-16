rule TTP_XOR_QUAD_CurrentVersionRun_e0dc {
  strings:
    $key_e0dc = { b3 b3 [2] 97 bd [2] bc 91 [2] 92 b3 [2] 86 a8 [2] 89 b2 [2] 97 af [2] 95 ae [2] 8e a8 [2] 92 af [2] 8e 80 }

  condition:
    any of them
}