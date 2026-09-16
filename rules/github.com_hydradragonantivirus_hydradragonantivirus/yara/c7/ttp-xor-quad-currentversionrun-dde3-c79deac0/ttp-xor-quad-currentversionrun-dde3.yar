rule TTP_XOR_QUAD_CurrentVersionRun_dde3 {
  strings:
    $key_dde3 = { 8e 8c [2] aa 82 [2] 81 ae [2] af 8c [2] bb 97 [2] b4 8d [2] aa 90 [2] a8 91 [2] b3 97 [2] af 90 [2] b3 bf }

  condition:
    any of them
}