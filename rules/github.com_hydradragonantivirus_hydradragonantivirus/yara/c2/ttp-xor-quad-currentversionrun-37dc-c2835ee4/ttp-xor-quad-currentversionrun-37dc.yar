rule TTP_XOR_QUAD_CurrentVersionRun_37dc {
  strings:
    $key_37dc = { 64 b3 [2] 40 bd [2] 6b 91 [2] 45 b3 [2] 51 a8 [2] 5e b2 [2] 40 af [2] 42 ae [2] 59 a8 [2] 45 af [2] 59 80 }

  condition:
    any of them
}