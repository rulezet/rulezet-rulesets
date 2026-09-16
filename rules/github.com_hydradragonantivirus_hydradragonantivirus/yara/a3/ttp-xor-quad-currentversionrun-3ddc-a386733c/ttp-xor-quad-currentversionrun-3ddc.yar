rule TTP_XOR_QUAD_CurrentVersionRun_3ddc {
  strings:
    $key_3ddc = { 6e b3 [2] 4a bd [2] 61 91 [2] 4f b3 [2] 5b a8 [2] 54 b2 [2] 4a af [2] 48 ae [2] 53 a8 [2] 4f af [2] 53 80 }

  condition:
    any of them
}