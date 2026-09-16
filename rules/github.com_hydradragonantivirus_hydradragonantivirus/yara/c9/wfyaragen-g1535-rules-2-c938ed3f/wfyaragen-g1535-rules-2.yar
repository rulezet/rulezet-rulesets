rule WFYARAGEN_G1535_rules_2 {
  meta:
    description = "Obfuscated eval-gzinflate"

  strings:
    $re = /@\$\w+\s*=\s*"e\\x76\\x61l\s*\(\s*\\x67\\x7Ai\\x6E\\x66\\x6C\\x61t\\x65\s*\(/ nocase

  condition:
    $re
}