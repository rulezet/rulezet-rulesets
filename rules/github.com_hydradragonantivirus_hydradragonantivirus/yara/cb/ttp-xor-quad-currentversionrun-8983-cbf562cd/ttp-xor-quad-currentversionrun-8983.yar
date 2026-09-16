rule TTP_XOR_QUAD_CurrentVersionRun_8983 {
  strings:
    $key_8983 = { da ec [2] fe e2 [2] d5 ce [2] fb ec [2] ef f7 [2] e0 ed [2] fe f0 [2] fc f1 [2] e7 f7 [2] fb f0 [2] e7 df }

  condition:
    any of them
}