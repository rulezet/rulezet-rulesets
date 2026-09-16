rule TTP_XOR_QUAD_CurrentVersionRun_6ddc {
  strings:
    $key_6ddc = { 3e b3 [2] 1a bd [2] 31 91 [2] 1f b3 [2] 0b a8 [2] 04 b2 [2] 1a af [2] 18 ae [2] 03 a8 [2] 1f af [2] 03 80 }

  condition:
    any of them
}