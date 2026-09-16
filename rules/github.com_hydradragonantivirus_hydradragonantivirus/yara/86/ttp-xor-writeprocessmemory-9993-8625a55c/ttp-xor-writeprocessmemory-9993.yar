rule TTP_XOR_WriteProcessMemory_9993 {
  strings:
    $key_9993 = { ce e1 [2] fc c3 [2] fa f6 [2] d4 f6 [2] eb ea }

  condition:
    any of them
}