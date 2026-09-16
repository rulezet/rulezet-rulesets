rule openxml_remote_content
{
 meta:
  ref = "https://www.defcon.org/html/defcon-22/dc-22-speakers.html#Crenshaw"
  author = "MalwareTracker.com @mwtracker"
  date = "Aug 10 2014"
  hash = "63ea878a48a7b0459f2e69c46f88f9ef"

  strings:
  $a = "schemas.openxmlformats.org" ascii nocase
  $b = "TargetMode=\"External\"" ascii nocase

  condition:
  all of them
}