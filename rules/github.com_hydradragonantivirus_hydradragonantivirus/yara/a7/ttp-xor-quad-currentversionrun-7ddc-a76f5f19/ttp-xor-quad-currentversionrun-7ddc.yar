rule TTP_XOR_QUAD_CurrentVersionRun_7ddc {
  strings:
    $key_7ddc = { 2e b3 [2] 0a bd [2] 21 91 [2] 0f b3 [2] 1b a8 [2] 14 b2 [2] 0a af [2] 08 ae [2] 13 a8 [2] 0f af [2] 13 80 }

  condition:
    any of them
}