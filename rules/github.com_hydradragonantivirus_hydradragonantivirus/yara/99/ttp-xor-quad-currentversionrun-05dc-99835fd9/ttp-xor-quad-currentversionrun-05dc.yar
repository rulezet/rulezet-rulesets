rule TTP_XOR_QUAD_CurrentVersionRun_05dc {
  strings:
    $key_05dc = { 56 b3 [2] 72 bd [2] 59 91 [2] 77 b3 [2] 63 a8 [2] 6c b2 [2] 72 af [2] 70 ae [2] 6b a8 [2] 77 af [2] 6b 80 }

  condition:
    any of them
}