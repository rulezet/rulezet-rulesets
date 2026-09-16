rule TTP_XOR_QUAD_CurrentVersionRun_eb83 {
  strings:
    $key_eb83 = { b8 ec [2] 9c e2 [2] b7 ce [2] 99 ec [2] 8d f7 [2] 82 ed [2] 9c f0 [2] 9e f1 [2] 85 f7 [2] 99 f0 [2] 85 df }

  condition:
    any of them
}