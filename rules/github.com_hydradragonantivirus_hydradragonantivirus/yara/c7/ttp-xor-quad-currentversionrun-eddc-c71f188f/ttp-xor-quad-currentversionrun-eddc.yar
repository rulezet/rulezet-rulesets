rule TTP_XOR_QUAD_CurrentVersionRun_eddc {
  strings:
    $key_eddc = { be b3 [2] 9a bd [2] b1 91 [2] 9f b3 [2] 8b a8 [2] 84 b2 [2] 9a af [2] 98 ae [2] 83 a8 [2] 9f af [2] 83 80 }

  condition:
    any of them
}