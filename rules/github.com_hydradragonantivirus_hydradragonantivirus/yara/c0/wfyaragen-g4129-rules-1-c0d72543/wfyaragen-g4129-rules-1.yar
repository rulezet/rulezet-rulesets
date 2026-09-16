rule WFYARAGEN_G4129_rules_1 {
  meta:
    description = "Malicious code meant to look like WordPress core"

  strings:
    $re = /\@include\s*\(\s*ABSPATH\s*\.\s*WPINC\s*\.\s*['"]\/Requests\/IPconfig\.ini['"]/ nocase

  condition:
    $re

}