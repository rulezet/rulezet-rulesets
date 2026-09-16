rule Win_Trojan_Dasmin_1
{
strings:
	$a0 = { 1cffd69bf94b351f1d0d8b31486872c0c2d2a1a1b95d0bf1c9bae5fbd39fc6c6e8b38a536fd3353341897a9dccb1d8f0826b525f0b13e78b9babbf7ad0084e24464e682725d3df }


condition:
	$a0
}