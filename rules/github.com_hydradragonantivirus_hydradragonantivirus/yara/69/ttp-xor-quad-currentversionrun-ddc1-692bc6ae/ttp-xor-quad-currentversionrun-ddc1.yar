rule TTP_XOR_QUAD_CurrentVersionRun_ddc1 {
  strings:
    $key_ddc1 = { 8e ae [2] aa a0 [2] 81 8c [2] af ae [2] bb b5 [2] b4 af [2] aa b2 [2] a8 b3 [2] b3 b5 [2] af b2 [2] b3 9d }

  condition:
    any of them
}