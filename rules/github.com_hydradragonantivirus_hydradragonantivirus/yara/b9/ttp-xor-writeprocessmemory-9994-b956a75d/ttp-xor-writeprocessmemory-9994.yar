rule TTP_XOR_WriteProcessMemory_9994 {
  strings:
    $key_9994 = { ce e6 [2] fc c4 [2] fa f1 [2] d4 f1 [2] eb ed }

  condition:
    any of them
}