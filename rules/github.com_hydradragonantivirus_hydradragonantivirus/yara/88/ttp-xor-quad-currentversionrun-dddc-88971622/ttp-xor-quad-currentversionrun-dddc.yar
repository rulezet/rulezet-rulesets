rule TTP_XOR_QUAD_CurrentVersionRun_dddc {
  strings:
    $key_dddc = { 8e b3 [2] aa bd [2] 81 91 [2] af b3 [2] bb a8 [2] b4 b2 [2] aa af [2] a8 ae [2] b3 a8 [2] af af [2] b3 80 }

  condition:
    any of them
}