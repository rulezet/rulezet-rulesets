rule TTP_XOR_WriteProcessMemory_049f {
  strings:
    $key_049f = { 53 ed [2] 61 cf [2] 67 fa [2] 49 fa [2] 76 e6 }

  condition:
    any of them
}